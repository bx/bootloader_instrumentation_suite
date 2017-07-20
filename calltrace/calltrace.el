;; # MIT License

;; # Copyright (c) 2017 Rebecca ".bx" Shapiro

;; # Permission is hereby granted, free of charge, to any person obtaining a copy
;; # of this software and associated documentation files (the "Software"), to deal
;; # in the Software without restriction, including without limitation the rights
;; # to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
;; # copies of the Software, and to permit persons to whom the Software is
;; # furnished to do so, subject to the following conditions:

;; # The above copyright notice and this permission notice shall be included in all
;; # copies or substantial portions of the Software.

;; # THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
;; # IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
;; # FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
;; # AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
;; # LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
;; # OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
;; # SOFTWARE.


(require 'org)
(require 'outline)
(require 'org-archive)

(set-display-table-slot standard-display-table 
                        'selective-display (string-to-vector "{repeated}"))

(setq org-archive-default-command 'org-archive-set-tag)
(setq org-tags-column 1)
(setq org-auto-align-tags nil)

(defun ct-fnregexp (&optional fn entry)
  "Returns a regular expression string that searches for a
headline with function entry or exit information.

 If FN is nil it returns a regular expression that finds any
function entry/exit headline, else it returns a a regular
expression that only matches headlines that contain that function
name (string).

If ENTRY is nil, then it will return a regular expression that
matches both function entries (calls) and exits (returns). If
entry is \">\" (string) then it returns a regular expression that
only matches entries, else it returns a regular expression that
only matches exits."

  (if (null fn)
      (setq fn "\\([-_.[:alnum:]]+\\)")
    (setq fn (concat "\\(" fn "\\)")))

  (cond ((null entry)
         (setq entry "\\(>\\|<\\)"))
        ((string entry ">")
         (setq entry "\\(>\\)"))
        (t
         (setq entry "\\(<\\)")))
  (concat "^[[:space:]]*" entry "[[:space:]]*" fn "\\(@0[xX][a-fA-F0-9]+\\)?[[:space:]]*" (regexp-quote "[") "*"))
  

(defun ct-function-entry-p ()
  "Tests if headline at current point is a function entry,
returns nil if it isn't"

  (let ((res (ct-get-function-match 1 t)))
    (string= res ">")))

(defun ct-function-entry-exit-p ()
  "Tests if headline at current point is a function
entry/exit. Returns nil if it isn't."
  (not (null (ct-get-function-match 0 t))))

(defun ct-get-function-match (n &optional noerror)
  "Tests if headline at current point matches current is a
function and returns the Nth group of the the ct-fnregexp.  If
NOERROR is nil, it signals an error if a mach is not found else
it returns nil"
  (let* ((h (org-element-at-point))
         (title (org-element-property :title h))         
         (res nil)
         (match nil)
         (re (ct-fnregexp)))
    (with-temp-buffer
      (insert title)
      (goto-char (point-min))
      (setq match (list
                   (re-search-forward re nil t)
                   (match-string n)))
      (if (null (car match))
          (if (null noerror)
              (error "No function name here")
            nil))
      (nth 1 match))))

(defun ct-next-function-headline (&optional visible-only)
  "Moves the current point to the next headline. If VISIBLE-ONLY
is not nil, it will only move the point to a currently visible
headline"
  (interactive)
  (let ((curr (point))
        (next (if visible-only (outline-next-visible-heading 1) (outline-next-heading)))
        (res nil))
    (while (and next (null res) (< (point) (point-max)))
      (if (ct-function-entry-exit-p)
          (setq res (point))
        (setq next (if visible-only (outline-next-visible-heading 1) (outline-next-heading)))))
    (if (= (point-max) (point))
        nil
      (point))))
  
(defun ct-function-name-at-current-headline ()
  "Returns the function name at the current headline, raises
error if it is not at a function headline"
  (let ((fn (ct-get-function-match 2 t)))
    fn))

(defun ct-set-to-hide (&optional unhide donthide)
  "Sets a flag to hide this function heading. If UNHIDE is not
nil then it unsets the hide flag. If DONTHIDE is not nil then it
doesn't perform an action that actually hides the subtree"
  (let ((a nil))
    (save-excursion
      (setq a (ct-is-hidden))
      (if unhide
          (progn
            (if a
                (progn
                  (org-back-to-heading t)                 
                  (org-toggle-tag org-archive-tag)))
            (if (null donthide)
                (org-show-context 'occur-tree)))
          (progn
            (if (null a)
                (progn
                  (org-back-to-heading t)
                  (org-toggle-archive-tag)
		  (if (null donthide)
		      (hide-subtree)))))))))

(defun ct-remove-all-hide-tags ()
  "Removes all tags that calltrace set to hide functions"
  (interactive)
  (org-map-entries (lambda ()
		     (org-set-tags-to (remove org-archive-tag (org-get-tags-at))))
		   nil 'file))

(defun ct-is-hidden ()
  "Checks if headline at current point is hidden"
  (not (null (member org-archive-tag (org-get-tags-at)))))

(defun ct-mark-dups (&optional visibleonly)
  "Marks any repeated adjacent function calls to be hidden. If
VISIBLEONLY is not nill, then it only operates on currently
visible headlines. Does not hide anything."
  (interactive)  
  (let ((prevfun nil)
	(currfun nil)
	(llast 0)
	(next t)
	(hide nil)
	(stack nil)
	(hasdups nil)
	(parent-is-hidden nil)
	(maxline (line-number-at-pos (point-max)))
	lspos level i)
    (save-excursion
      (goto-char (point-min))
      (if (null (ct-function-entry-exit-p))
	  (ct-next-function-headline visibleonly))
      (while next      
	(setq hide nil)
	(setq lspos (line-number-at-pos (point)))
	(message "(mark) processing line %s of %s" lspos maxline)	
	(setq currfun (ct-function-name-at-current-headline))
	(setq level (org-reduced-level (org-outline-level)))
	(if (ct-function-entry-p)
	    (progn
	      (if (not (equal level llast))
		  (setq prevfun nil)
		(if (or (string= prevfun currfun) parent-is-hidden)
		    (setq hide t)))
	      (push currfun stack))
	  (progn ; function exit
	    (pop stack)
	    (if (and (< level llast) (> llast 0))
		(dotimes (i (- (- llast level) 1))
		  (pop stack))) ; pop the extra frames off
	    (org-backward-heading-same-level 1 (not visibleonly)) ;check if entry is hidden
	    (setq hide (and (ct-function-entry-exit-p) (ct-function-entry-p) (string= currfun (ct-function-name-at-current-headline)) (ct-is-hidden)))
	    (org-forward-heading-same-level 1 (not visibleonly)))) ;go back to origional location
	(setq llast level)
	(setq prevfun currfun)
	(ct-set-to-hide (not hide) t)
	(setq hasdups (or hasdups hide))
	(setq next (ct-next-function-headline visibleonly))))
    hasdups))

(defun ct-collapse-dups-until-none (&optional savetags)
  "Marks duplicates to be hidden and then iteratively hides
repeated adjacent function calls until there are none. If
SAVETAGS is not nil, it does not remove existing hide tags."
  (interactive "P")
  (outline-show-all)
  (if savetags
      (ct-coalesce-hidden)    
    (let ((haddups t)
	  (i 0))
      (while haddups
	(message "collapse iteration %s" i)
	(setq haddups (ct-mark-dups t))
	(setq i (+ i 1))
	(ct-hide-hidden))))
    (org-remove-occur-highlights t)
    (ct-coalesce-hidden))
  
(defun ct-collapse-dups ()
  "Marks duplicates to be hidden and then hides current set of
repeated adjacent function calls."
  (ct-remove-all-hide-tags)
  (ct-mark-dups)
  (ct-hide-hidden)
  (org-remove-occur-highlights t)
  (ct-coalesce-hidden))

(defun ct-save-hiding-state (&optional file)
  "Saves state of what is hidden in current buffer to a file FILE so that it can be restored later (as long as the original file is not modified)"
  (interactive "F")
  (if (null file)
      (setq file "hidingdata"))
  (let ((overlays (org-outline-overlay-data)))
    (with-temp-buffer
      (insert (format "(setq overlays '%s)" overlays))
      (ignore-errors (delete-file file))
      (append-to-file (point-min) (point-max) file))))


(defun ct-restore-hiding-state (&optional file)
  "Restores state of what was hidden from FILE"
  (interactive "f")
  (if (null file)
      (setq file "hidingdata"))  
  (let ((overlays nil))
    (with-temp-buffer (insert-file-contents file)		      
		      (eval-buffer))
    (org-set-outline-overlay-data overlays)))


(defun ct-format-linenumber (line)
  (format "%08d" line))


(defun ct-format-unique-functions-filename (prefix minline maxline funname)
  (let ((dir ""))
    (if (file-directory-p prefix)
	(setq dir "/"))
    (concat prefix dir minline "-" maxline "-" funname ".txt")))

(defun ct-get-unique-functions-after-point (&optional file min max lastfn)
  "Prints out the set of functions that are called after (and
including) the current headline. Optionally writes results to
FILE if FILE not nil. If FILE is t then it writes files to
present working directory otherwise it prepends the string to the
filename it generates and uses the result as a path.  Bases
filename on start function if LASTFN is nil else bases filename
on LASTFN"
  (interactive "P")
  (let ((oldpoint (point))
	(funs nil)
	(funname nil)
	(contents nil)
	(minpoint nil)
	(maxpoint nil)
	(absminline nil)
	(absmaxline nil)
	(overlays nil)
	(startname nil)
	(outpath "")
	(next t))
    (if (not (eq file t))
	(setq outpath file))    
    (if (null min)
	(setq min oldpoint))
    (if (null max)
	(setq max (point-max)))
    (if (not (null file))
	(progn
	  (save-excursion
	    (goto-char min)
	    (setq minpoint (org-element-property :begin (org-element-at-point)))
	    (goto-char max)
	    (if (= max (line-beginning-position))
		(progn
		  (forward-line -1)
		  (setq max (point))))
	    (beginning-of-line)
	    (setq maxpoint (org-element-property :begin (org-element-at-point))))
	  ;(setq overlays (org-outline-overlay-data))
	  ;(remove-overlays)
	  (setq absminline (line-number-at-pos minpoint))
	  (setq absmaxline (line-number-at-pos maxpoint))
	  ;(org-set-outline-overlay-data overlays) ; restore overlays
	  ;(message "min (%s,%s) max (%s,%s)" min absminline max absmaxline)
	  (goto-char min)
	  (beginning-of-line)
	  (if (null lastfn)
	      (setq startname (ct-function-name-at-current-headline))
	    (save-excursion
	      (goto-char max)
	      (beginning-of-line)
	      (setq startname (ct-function-name-at-current-headline))))
	  (setq outpath (ct-format-unique-functions-filename outpath (ct-format-linenumber absminline) (ct-format-linenumber absmaxline) startname))))
    
    
    (if min
	(goto-char min))
    
    (while next
      (when (ct-function-entry-exit-p)
	(setq funname (ct-function-name-at-current-headline))
	(if (null (member funname funs))
	    (push funname funs)))	  
      (setq next (ct-next-function-headline))
      (if (and max next (> next max))
	      (setq next nil)))
    (if (> (length outpath) 0)
	(with-temp-buffer
	  (message "writing results to: %s" outpath)
	  (insert (mapconcat 'identity funs "\n"))
	  (ignore-errors (delete-file outpath))
	  (append-to-file (point-min) (point-max) outpath))
      (message (concat "{" (mapconcat 'identity funs ", ") "}")))
    (goto-char oldpoint)
    funs))

(defun ct-get-unique-functions-before-point (&optional file point)
  (interactive "P")
  (let ((oldpoint (point)))
    (if (null point)
	(setq point (point)))
    (if (= point (line-beginning-position))
	(progn
	  (forward-line -1)
	  (setq point (point))))
    (setq point (line-end-position))
    (ct-get-unique-functions-after-point file (point-min)  point t)
    (goto-char oldpoint)))

(defun ct-get-unique-functions-in-region (&optional file min max)
  "Prints out the set of functions that are called after (and
including) the current headline. Optionally writes results to
FILE if FILE not nil."
  (interactive "P")
  (if (null min)
      	(setq min (region-beginning)))
  
  (if (null max)
      (setq max (region-end)))
  (if (< max min)
      (let ((tmp min))
	(setq min max)
	(setq max tmp)))
  (ct-get-unique-functions-after-point file min max))


(defun ct-hide-hidden ()
  "Does the work to hide headlines that have been marked to
hide."
  (let ((next t)
	(maxline (line-number-at-pos (point-max))))
      (show-all)
      (goto-char (point-min))
      (while next
	(message "(hide?) processing line %s of %s" (line-number-at-pos) maxline)
	(if (ct-is-hidden)
	    (outline-flag-region (line-beginning-position) (line-end-position) t)
	  (progn
	    (outline-flag-region (line-end-position) (line-end-position) nil)
	    (beginning-of-line)))
	(setq next (ct-next-function-headline)))))


(defun ct-coalesce-hidden ()
  "Merges together adjacent hidden lines"
  (interactive)
  (let ((next t)
	(hstart -1)
	(hend -1)
	(maxline (line-number-at-pos (point-max))))
    (goto-char (point-min))
    (while next
      (message "(coalesce?) processing line %s of %s" (line-number-at-pos) maxline)
      (if (or (outline-invisible-p) (ct-is-hidden))
	  (progn
	    (if (= hstart -1)
		(setq hstart (point)))
	    (setq hend (line-end-position)))
	(progn
	  (if (> hend (point-min))
	      (progn
		(outline-flag-region hstart hend t)
		(setq hstart -1)
		(setq hend -1)))))
      (setq next (ct-next-function-headline)))))

(provide 'calltrace)
