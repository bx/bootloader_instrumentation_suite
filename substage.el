;; MIT License

;; Copyright (c) 2017 Rebecca ".bx" Shapiro

;; Permission is hereby granted, free of charge, to any person obtaining a copy
;; of this software and associated documentation files (the "Software"), to deal
;; in the Software without restriction, including without limitation the rights
;; to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
;; copies of the Software, and to permit persons to whom the Software is
;; furnished to do so, subject to the following conditions:

;; The above copyright notice and this permission notice shall be included in all
;; copies or substantial portions of the Software.

;; THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
;; IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
;; FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
;; AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
;; LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
;; OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
;; SOFTWARE.

(defun mkpath (dir file)
  (concat dir "/" file))

(defun create-substage-calltraces (calltracefile substages outputdir)
  (if (not (file-directory-p outputdir))
      (make-directory outputdir t))
  (if (stringp substages) ; then open file to read out proposed substages
      (with-temp-buffer
	(insert-file-contents substages)
	(eval-buffer)))
  (save-excursion 
    (find-file calltracefile)
    (goto-char (point-min))  
    (show-all)
    (message "substages %s" substages)
    (let ((min (pop substages)))
      (mapc (lambda (max) (ct-get-unique-functions-after-point outputdir (line-beginning-position min) (line-beginning-position (+ 1 max))) (message "%s-%s" min max) (setq min max)) substages))))

  

(provide 'boot-substage)

